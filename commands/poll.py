# Copyright 2020-2024 Daniel Weiner
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import base64
import logging
from bs4 import BeautifulSoup
import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError, HTTPError, Timeout, RequestException
from urllib3.util.retry import Retry
from monitor.lib import ConversionFailure, Metric, MetricPipeline, Result


class Poller(object):

    class Context(object):
        """
        Wraps the state necessary for persistently tracking the Device across
        polling calls. We use a shared session and token to not require as many
        connections back to the device.
        """
        def __init__(self, name: str, config: dict, logger: logging.Logger = None):
            self.name = name
            self.config = config
            self.logger = logger
            self.session = None
            self.token = None
            self.errors = 0

        def ValidateConfig(self):
            pass

    def __init__(self):
        """
        The only thing stored in state here is the context objects which are keyed
        by their device name from the configuration.
        """
        self.contexts = dict()

    @staticmethod
    def MakeSession(config: dict) -> requests.Session:
        """

        :param config:
        :return:
        """
        retry_strategy = Retry(
            total=3,  # Total number of retries
            status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
            allowed_methods=['HEAD', 'GET', 'OPTIONS'],  # Retry only for these methods
            backoff_factor=1  # Wait 1 second between retries
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session = requests.Session()

        session.mount('http://', adapter)
        session.mount('https://', adapter)

        return session

    @staticmethod
    def MakeRequest(callback, logger=None) -> [requests.Response, None]:
        resp = None
        try:
            resp = callback()
            resp.raise_for_status()
        except (ConnectionError, Timeout):
            if logger:
                logger.exception('Connection error occurred. This is likely retryable.')
        except HTTPError as e:
            if logger:
                logger.exception('HTTP error occurred: {}'.format(e))
        except RequestException as e:
            if logger:
                logger.exception('Request exception occurred: {}'.format(e))
        finally:
            if resp:
                resp.close()
        return resp

    @staticmethod
    def GetAuthToken(config: dict, session: requests.Session,
                     logger: logging.Logger = None) -> [str, None]:
        """

        :param config:
        :param session:
        :param logger:
        :return:
        """
        protocol = config.get('protocol', 'https')
        url = '{}://{}/cmconnectionstatus.html'.format(protocol, config['address'])

        username = config['username']
        password = config['password']
        verify_ssl = config['verify_ssl'] if protocol == 'https' else False

        token = '{}:{}'.format(username, password)
        auth_hash = base64.b64encode(token.encode('ascii')).decode()
        auth_url = '{}?login_{}'.format(url, auth_hash)

        if logger:
            logger.debug('Auth token: {}'.format(token))
            logger.debug('Auth hash: {}'.format(auth_hash))
            logger.debug('Auth url: {}'.format(auth_url))

        resp = Poller.MakeRequest(lambda: session.get(
            auth_url,
            verify=verify_ssl,
            headers={'Authorization': 'Basic {}'.format(auth_hash)}), logger=logger)

        if not resp:
            if logger:
                logger.error("Error authenticating with '{}'".format(url))

            return None

        if resp.status_code != 200:
            if logger:
                logger.error("Error authenticating with '{}': [{}] {}".format(
                    url, resp.status_code, resp.reason))
            return None

        if 'Password:' in resp.text:
            if logger:
                logger.error('Error authenticating with device. Check username/password')

            return None

        token = resp.text
        return token

    @staticmethod
    def GetData(config: dict,
                session: requests.Session,
                token: str,
                logger: logging.Logger = None) -> [str, None]:
        """

        :param config:
        :param session:
        :param token:
        :param logger:
        :return:
        """
        protocol = config.get('protocol', 'https')
        url = '{}://{}/cmconnectionstatus.html'.format(protocol, config['address'])

        if logger:
            logging.info('Retrieving stats from: {}'.format(url))
            logging.debug('Cookies: %s', session.cookies)

        if token:
            url = '{}?ct_{}'.format(url, token)
            if logger:
                logging.debug('Full url: {}'.format(url))

        verify_ssl = config['verify_ssl'] if protocol == 'https' else False
        resp = Poller.MakeRequest(lambda: session.get(url, verify=verify_ssl), logger=logger)

        if not resp or resp.status_code != 200:
            if logger:
                if not resp:
                    logger.error("Error retrieving data from '{}'".format(url))
                else:
                    logger.error("Error retrieving data from '{}': [{}] {}".format(
                        url, resp.status_code, resp.reason))
            return None

        data = resp.content.decode('utf-8')

        if 'Password' in data:
            if logger:
                logger.error('Authentication error. Retry with a new session.')
            if not config['auth_required']:
                logger.warning('Auth is disabled but a login is required.')
            return None

        return data

    @staticmethod
    def ParseData(data: str, logger: logging.Logger = None) -> [dict, None]:
        """

        :param data:
        :param logger:
        :return:
        """
        # As of Aug 2019 the SB8200 has a bug in its HTML
        # The tables have an extra </tr> in the table headers, we have to remove it so
        # that Beautiful Soup can parse it
        # Before: <tr><th colspan=7><strong>Upstream Bonded Channels</strong></th></tr>
        # After: <tr><th colspan=7><strong>Upstream Bonded Channels</strong></th>
        data = data.replace('Bonded Channels</strong></th></tr>', 'Bonded Channels</strong></th>', 2)

        soup = BeautifulSoup(data, 'html.parser')
        stats = {'downstream': [], 'upstream': []}

        # Parse the downstream stats data
        for table_row in soup.find_all('table')[1].find_all('tr'):
            if table_row.th:
                continue

            channel_id = table_row.find_all('td')[0].text.strip()

            # Some firmwares have a header row not already skipped by "if table_row.th", skip it
            # if channel_id isn't an integer
            if not channel_id.isdigit():
                continue

            frequency = table_row.find_all('td')[3].text.replace(' Hz', '').strip()
            power = table_row.find_all('td')[4].text.replace(' dBmV', '').strip()
            snr = table_row.find_all('td')[5].text.replace(' dB', '').strip()
            corrected = table_row.find_all('td')[6].text.strip()
            uncorrectables = table_row.find_all('td')[7].text.strip()

            stats['downstream'].append({
                'channel_id': channel_id,
                'frequency': frequency,
                'power': power,
                'snr': snr,
                'corrected': corrected,
                'uncorrectables': uncorrectables
            })

        if not stats['downstream']:
            if logger:
                logger.error('No downstream channels stats found.')

        # Parse the upstream stats data
        for table_row in soup.find_all('table')[2].find_all('tr'):
            if table_row.th:
                continue

            channel_id = table_row.find_all('td')[1].text.strip()

            # Some firmwares have a header row not already skipped by "if table_row.th", skip it
            # if channel_id isn't an integer
            if not channel_id.isdigit():
                continue

            frequency = table_row.find_all('td')[4].text.replace(' Hz', '').strip()
            power = table_row.find_all('td')[6].text.replace(' dBmV', '').strip()

            stats['upstream'].append({
                'channel_id': channel_id,
                'frequency': frequency,
                'power': power,
            })

        if not stats['upstream']:
            if logger:
                logger.error('No upstream channels stats found.')

        return stats

    @staticmethod
    def ProcessDevice(context, pipeline: MetricPipeline) -> bool:
        """

        :param context:
        :param pipeline:
        :return:
        """
        if context.logger:
            context.logger.info("Poll device: {}".format(context.name))

        if context.session is None:
            context.session = Poller.MakeSession(context.config)
            context.token = None

        if context.config['auth_required']:
            context.token = Poller.GetAuthToken(
                context.config,
                context.session,
                logger=context.logger)

            if not context.token:
                if context.logger:
                    context.logger.error("Failed to get auth token for device '{}' ({})".format(
                        context.name, context.config['address']))

                return False

            if context.logger:
                context.logger.info("Refreshed auth token for '{}' ({})".format(
                        context.name, context.config['address']))

        data = Poller.GetData(context.config, context.session, context.token,
                              logger=context.logger)

        if not data:
            if context.logger:
                context.logger.error("No data to parse from '{}' ({})".format(
                    context.name, context.config['address']))

            if context.config['clear_auth_on_html_error']:
                context.session = None

            return False

        stats = Poller.ParseData(data, logger=context.logger)
        if not stats \
                or ('upstream' not in stats or len(stats['upstream']) == 0) \
                or ('downstream' not in stats or len(stats['downstream']) == 0):
            context.errors += 1

            if context.logger:
                context.logger.error('Failed to parse usable stat data (errors={})'.format(
                    context.errors))

            if context.errors >= 3:
                context.session = None

            return False

        tags = {'device': context.name}
        tags.update(context.config.get('tags', {}))
        metrics = []

        for upstream in stats['upstream']:
            mtags = tags.copy()
            mtags['channel'] = int(upstream['channel_id'])
            metric = Metric(upstream['channel_id'], 'upstream', tags=mtags)

            for field, value in upstream.items():
                if field == 'channel_id':
                    continue
                metric.AddField(field, value)

            metrics.append(metric)

        for downstream in stats['downstream']:
            mtags = tags.copy()
            mtags['channel'] = int(downstream['channel_id'])
            metric = Metric(downstream['channel_id'], 'downstream', tags=mtags)

            for field, value in downstream.items():
                if field == 'channel_id':
                    continue
                metric.AddField(field, value)

            metrics.append(metric)

        try:
            pipeline(metrics)
        except ConversionFailure:
            pass

        return True

    @staticmethod
    def Poll(state, config: dict, logger: logging.Logger, pipeline: MetricPipeline) -> Result:
        """

        :param state:
        :param config:
        :param logger:
        :param pipeline:
        :return:
        """
        success = True
        for device, cfg in config.items():
            # Create the context iof it doesn't exist. It's possible to have a new context
            # created anytime at runtime if the config is reloaded dynamically.
            if device not in state.contexts:
                state.contexts[device] = Poller.Context(device, config[device], logger=logger)
                state.contexts[device].ValidateConfig()

            # Process the device and pass it its given context. The context here will store
            # persistent information like the keep-alived connection, token, and session.
            if not state.ProcessDevice(state.contexts[device], pipeline):
                success = False

        return Result.SUCCESS if success else Result.FAILURE

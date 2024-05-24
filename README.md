# Arris Modem Poller

This project is based off the now defunct [arris_cable_modem_stats](https://github.com/andrewfraley/arris_cable_modem_stats/tree/main) project and utilizes the [PyMonitorLib](https://github.com/Aralocke/PyMonitorLib) project for handling the polling runtime.

## Monitoring a Modem

I have many piece of my home network under monitoring. It made sense to want to do the same thing for my cable modem. I currently only have an Arris SB8200 so that is all that is supported in the system. It wouldn't be hard to add support for others if necessary.

This project will generate stat data and send it to an Influxdb-v2 database based on the configuration file.

# Deployment

I use this running in a container. A `Containerfile` is provided for use and expects the configuration file to be mounnted into the container at `/etc/monitor.conf`.

I build the container from this repository and then use a separate container which injects the configuration file directly intp the image.

See the [Example Configuration](config/example.conf) for information on how to use this.

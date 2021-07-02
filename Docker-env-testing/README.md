# Docker testing environment for JIRA

## Purpose

On a daily basis, this is what is being used to verify the development of the Addon against JIRA software, it is composed of:

- A JIRA Software container (you can get easily a trial version when the container bootstraps)
- An NGINX acting as the SSL proxy with an unsecure certificate (the Addon requires to talk to JIRA over SSL)
- A simple proxy running on Squid in a container, to validate the Addon behaviours behind a proxy
- A Splunk standalone container

## Start

Use Visual Studio for the better experience, or use a docker-compose command to start the environment:

```
docker-compose up -d
```

## Stop and destroy

To stop and destroy:

```
docker-compose stop
docker-compose rm -f
```

Optional, to purge the unused volumes and free storage:

```
docker volume prune -f
```

## Accesses

*To access JIRA:*

- https://localhost:8081

*To access Splunk:*

- https://localhost:8000

## TA configuration in Splunk

Once you have setup JIRA (get the trial, create an account), use in the TA config page:

- JIRA url: nginx:8081
- JIRA login: <the loging you have created>
- JIRA password: <the password that was assigned>

*Note: you cannot verify the certificate as it is an insecure self signed*

Proxy:

- Proxy host: proxy
- Proxy port: 3128

And that's it! You have a fully functional environment to play with.

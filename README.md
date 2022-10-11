This is a daemon used to manage the test-cluster system managed by the SDKQE team.

It exposes a REST API and allows you to allocate/deallocate clusters inside
of the corporate network for the purposes of doing testing.

### Regenerating Trusted Certs

The certs can be regenerated using the letsencrpyt certbot and aws route53 credentials

#### Generate the new certs

```
docker run -it --rm -v "/etc/letsencrypt:/etc/letsencrypt" -v "/var/lib/letsencrypt:/var/lib/letsencrypt" -e "AWS_ACCESS_KEY_ID=XXX" -e "AWS_SECRET_ACCESS_KEY=XXX" certbot/dns-route53 certonly --dns-route53 -d "*.cbqeoc.com"
```

#### Updating the config

Put the paths to these files in the ~/.cbdynclusterd.toml config file

trusted-root-ca-path: /etc/letsencrypt/live/cbqeoc.com/chain.pem

trusted-private-key-path: /etc/letsencrypt/live/cbqeoc.com/privkey.pem

trusted-cert-path: /etc/letsencrypt/live/cbqeoc.com/cert.pem

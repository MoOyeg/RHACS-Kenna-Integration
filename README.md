# RHACS-Kenna-Integration
Red Hat ACS Integration for exporting vulnerability Information with KENNAfrom RHACS into Kenna KDE Format.

## Status: Prototype

## How to run
- pip install -r ./app/requirements.txt
- python ./run.py
- Point [ACS WebHook](https://docs.openshift.com/acs/3.74/integration/integrate-using-generic-webhooks.html) to use Configured Ip/Port in [run.py](./run.py)

## How to run test
- pytest
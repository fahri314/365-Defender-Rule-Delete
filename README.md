# 365-Defender-Rule-Delete

The limit for adding rules in Defender is 1,000. To add new rules, you must delete unused ones. You can use this script to delete unused rules in bulk.

## Config File

Before running the script, you must modify the values in the config file. You can obtain this data from the network section of your browser while logged in to the session at the address below.

<https://security.microsoft.com/v2/advanced-hunting?tid=your_tenant_id>

## Dependencies

```bash
python3 -m pip install requests
```

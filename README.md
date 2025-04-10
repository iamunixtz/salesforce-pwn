## Usage

```bash
python poc.py -h
usage: poc.py [-h] -u URL [-o [OBJECTS [OBJECTS ...]]] [-l] [-c] [-a AURA_CONTEXT] [-r RECORD_ID] [-d] [-f] [-s]

Exploit Salesforce through the aura endpoint with the guest privilege

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     set the SITE url. e.g. http://url/site_path
  -o [OBJECTS [OBJECTS ...]], --objects [OBJECTS [OBJECTS ...]]
                        set the object name. Default is "User". Juicy Objects: Case,Account,User,Contact,Document,Cont
                        entDocument,ContentVersion,ContentBody,CaseComment,Note,Employee,Attachment,EmailMessage,CaseE
                        xternalDocument,Attachment,Lead,Name,EmailTemplate,EmailMessageRelation
  -l, --listobj         pull the object list.
  -c, --check           only check aura endpoint
  -a AURA_CONTEXT, --aura_context AURA_CONTEXT
                        set your valid aura_context
  -r RECORD_ID, --record_id RECORD_ID
                        set the record id to dump the record
  -d, --dump_objects    dump a small number of objects accessible to guest users and save them in files.
  -f, --full            if set with -d, dump all pages of objects.
  -s, --skip            if set with -d, skip objects already dumped.
```


## Read More 
https://web.archive.org/web/20250000000000*/https://www.enumerated.de/index/salesforce

## Credit 
https://github.com/moniik/

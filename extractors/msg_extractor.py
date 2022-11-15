import mailparser
import os
import logging
import json
import sys
import shutil
import hashlib
import re
import base64
import json

############################ MSG ############################
# https://pypi.org/project/mail-parser/
# https://github.com/SpamScope/mail-parser
# $ sudo apt-get install libemail-outlook-message-perl
# pip install mail-parser
#############################################################

class MSGExtractor():
    def __init__(self):
        try:
            file_path = os.path.join('config', 'ioc_definitions.json')
            with open(file_path, 'r', encoding='utf-8') as config_file:
                self.ioc_definitions = json.load(config_file)
        except:
            print(f"[ERROR] Error loading '{file_path}' file")
            logging.error(f"Error loading '{file_path}' file")
            sys.exit(1)

        try:
            file_path = os.path.join('config', 'header_whitelist.json')
            with open(file_path, 'r', encoding='utf-8') as whitelist_file:
                loaded_data = json.load(whitelist_file)
                self.x_header_whitelist = loaded_data['headers']
        except:
            print(f"[ERROR] Error loading '{file_path}' file")
            logging.error(f"Error loading '{file_path}' file")
            sys.exit(1)

        try:
            file_path = os.path.join('config', 'interesting_headers.json')
            with open(file_path, 'r', encoding='utf-8') as interesting_headers_file:
                loaded_data = json.load(interesting_headers_file)
                self.interesting_headers = loaded_data['headers']
        except:
            print(f"[ERROR] Error loading '{file_path}' file")
            logging.error(f"Error loading '{file_path}' file")
            sys.exit(1)

    def process_sample(self, sample_path):
        self.sample_path = sample_path
        self.sample_dir, self.sample_file = os.path.split(self.sample_path)
        self.sample_name, self.sample_extension = os.path.splitext(
            self.sample_file)

        print(f"[INFO] Processing '{self.sample_path}'")

        self.anal_dir = os.path.join(self.sample_dir, self.sample_name)
        if not os.path.isdir(self.anal_dir):
                os.mkdir(self.anal_dir)
                os.mkdir(os.path.join(self.anal_dir, 'attachments'))

        self.anal_path = os.path.join(self.anal_dir, '.'.join([self.sample_name, 'msg']))
        print(f"[INFO] Ready for parsing '{self.anal_path}' file")
        logging.info(f"Ready for parsing '{self.anal_path}' file")
        shutil.copy(os.path.join(self.sample_path), self.anal_path)
        self.message = mailparser.parse_from_file_msg(self.anal_path)
        self.msg_extractor()

    def msg_extractor(self):
        mail = self.message
        extracted_data = dict()

        # BODY
        # hyperlinks are shown inside '< >'
        body = mail.body
        extracted_data['email_body'] = body
        file_path = os.path.join(self.anal_dir, 'email_body.txt')
        with open(file_path, "w") as out_file:
            out_file.write(body)
        print(f"[INFO] Extracted email body to '{file_path}'")
        logging.info(f"Extracted email body to '{file_path}'")

        # HEADERS
        extracted_data['interesting_headers'] = []
        extracted_header_path = os.path.join(self.anal_dir, 'header.txt')
        header = mail.headers
        received_raw = mail.received_raw
        received_json = mail.received_json

        file_path = os.path.join(self.anal_dir, 'received_parsed.json')
        with open(file_path, "w") as out_file:
            out_file.write(received_json)
        print(f"[INFO] Parsed 'Received' headers to '{file_path}'")
        logging.info(f"Parsed 'Received' headers to '{file_path}'")

        with open(extracted_header_path, "w") as out_file:
            for entry in received_raw:  # mail.headers does not provide all the "Received" entries
                out_file.write(f"Received: {entry}\n")
            for key, value in header.items():
                if key in self.interesting_headers:
                    extracted_data['interesting_headers'].append(
                        f"{key}: {value}")
                if key == "Received":   # "Received:" entries are already written  to the output file
                    continue
                if "IronPort" in key:
                    continue
                elif not key.startswith("X"):
                    out_file.write(f"{key}: {value}\n")
                elif key in self.x_header_whitelist:
                    out_file.write(f"{key}: {value}\n")
        print("[INFO] Extracted all email headers")
        logging.info('Extracted all email headers')

        # DATA from HEADERS
        extracted_data['email_entry_id'] = mail.message_id

        extracted_data['email_received_time'] = f"{mail.date} UTC {mail.timezone}"

        extracted_data['email_sender'] = dict(
            name=mail.from_[0][0],
            address=mail.from_[0][1])

        extracted_data['email_recipients'] = []
        for name, address in mail.cc:
            extracted_data['email_recipients'].append(dict(
                name=name,
                address=address))

        # only name wihtout the email address
        # extracted_data['email_to_name'] = mail.to[0][0]   # REDUNDANT

        # ORIGINAL VERSION STORES ONLY NAMES, NOT A NAME:EMAIL DICTIONARY
        extracted_data['email_cc'] = []
        for name, address in mail.cc:
            extracted_data['email_cc'].append(dict(
                name=name,
                address=address))

        extracted_data['email_bcc'] = []
        for name, address in mail.bcc:
            extracted_data['email_bcc'].append(dict(
                name=name,
                address=address))

        extracted_data['email_subject'] = mail.subject

        print("[INFO] Parsed and extracted data from email headers")
        logging.info('Parsed and extracted data from email headers')

        extracted_data['email_attachments'] = []
        attachments = mail.attachments
        for entry in attachments:
            local_path = os.path.join(self.anal_dir, 'attachments', entry['filename'])
            print(f"[INFO] Extracted attachment to '{local_path}'")
            encoded_payload = entry['payload']
            decoded_payload = base64.urlsafe_b64decode(encoded_payload)
            with open(local_path, "wb") as att_file:
                att_file.write(decoded_payload)

            md_5_sum = hashlib.md5(decoded_payload).hexdigest()
            sha_1_sum = hashlib.sha1(decoded_payload).hexdigest()
            sha_256_sum = hashlib.sha256(decoded_payload).hexdigest()

            extracted_data['email_attachments'].append(dict(
                name=entry['filename'],
                type=entry['mail_content_type'],
                md5=md_5_sum,
                sha1=sha_1_sum,
                sha256=sha_256_sum
            ))

        # extracted_data['email_sender_mail_type'] = "!!! -----> UNSUPPORTED <----- !!!"
        # extracted_data['email_body_format'] = "!!! -----> UNSUPPORTED <----- !!!"

        # IOCs
        extracted_data['iocs'] = []
        ioc_regexes = self.ioc_definitions['definitions']
        for ioc_type, ioc_data in ioc_regexes.items():
            data = sorted(
                set(re.findall(ioc_data['rgx'], body, re.IGNORECASE)))
            if data:
                ioc_entry = {}
                ioc_entry.update({ioc_type: data})
                extracted_data['iocs'].append(ioc_entry)
        if extracted_data['iocs']:
            print(f"[INFO] Extracted IOCs")
            logging.info(f"Extracted IOCs")

        file_path = os.path.join(self.anal_dir, 'extracted_data.json') 
        with open(file_path, "w") as out_file:
            out_file.write(json.dumps(
                extracted_data, indent=2, sort_keys=False))
        print(f"[INFO] Written extracted data to '{file_path}'")
        logging.info(f"Written extracted data to '{file_path}'")

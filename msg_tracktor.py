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

class ENTITY_MSGTRACTOR():
    def __init__(self):
        try:
            with open(os.path.join('config', 'ioc_definitions.json'), 'r', encoding='utf-8') as config_file:
                self.ioc_definitions = json.load(config_file)
        except:
            print('ERROR: Error loading config.json file')
            logging.error('Error loading config.json file')
            sys.exit(0)

        self.x_header_whitelist = ["X-Received", "X-Receiver", "X-Sender", "X-Report-Abuse",
                                   "X-Mailer", "X-Postmaster-Msgtype", "X-PHP-Originating-Script",  "X-Notes-Item"]
        self.interesting_headers = ["Return-Path",
                                    "Message-Id", "Message-ID",  "List-ID"]

    def process_sample(self, sample_path):

        self.sample_path = sample_path
        self.sample_dir, self.sample_file = os.path.split(self.sample_path)
        self.sample_name, self.sample_extension = os.path.splitext(
            self.sample_file)
            
        self.anal_dir = os.path.join(self.sample_dir, self.sample_name)
        if not os.path.isdir(self.anal_dir):
                os.mkdir(self.anal_dir)
                os.mkdir(os.path.join(self.anal_dir, 'att'))

        print('INFO: Processing ' +
                  self.sample_extension + ' sample')

        self.anal_path = os.path.join(self.anal_dir, '.'.join([self.sample_name, 'msg']))
        print("INFO: MSG ready for extractor")
        logging.info('MSG ready for extractor')
        shutil.copy(os.path.join(self.sample_path), self.anal_path)
        self.message = mailparser.parse_from_file_msg(self.anal_path)
        self.msg_extractor()

    def msg_extractor(self):
        mail = self.message
        extracted_data = dict()

        # hyperlinks are shown inside '< >'
        print("INFO: Extracting body")
        logging.info('Extracting body')
        body = mail.body
        extracted_data['email_body'] = body
        with open(os.path.join(self.anal_dir, 'email_body.txt'), "w") as out_file:
            out_file.write(body)

        print("INFO: Extracting headers")
        logging.info('Extracting headers')
        extracted_data['interesting_headers'] = []
        extracted_header_path = os.path.join(self.anal_dir, 'header.txt')
        header = mail.headers
        received_raw = mail.received_raw
        received_json = mail.received_json

        with open(os.path.join(self.anal_dir, 'received_parsed.json'), "w") as out_file:
            out_file.write(received_json)

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

        print("INFO: Extracting general data")
        logging.info('Extracting general data')

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

        extracted_data['email_attachments'] = []
        attachments = mail.attachments
        for entry in attachments:
            local_path = os.path.join(self.anal_dir, 'att', entry['filename'])
            print(f"INFO: Extracted attachment to {local_path}")
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

        print("INFO: Extracting IOCs")
        logging.info('Extracting IOCs')
        extracted_data['iocs'] = []
        ioc_regexes = self.ioc_definitions['definitions']
        for ioc_type, ioc_data in ioc_regexes.items():
            data = sorted(
                set(re.findall(ioc_data['rgx'], body, re.IGNORECASE)))
            if data:
                ioc_entry = {}
                ioc_entry.update({ioc_type: data})
                extracted_data['iocs'].append(ioc_entry)

        with open(os.path.join(self.anal_dir, 'extracted_data.json'), "w") as out_file:
            out_file.write(json.dumps(
                extracted_data, indent=2, sort_keys=False))
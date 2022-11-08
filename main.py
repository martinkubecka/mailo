import os
import argparse
import logging
import sys
import datetime

from eml_tractor import ENTITY_EMLTRACTOR
from msg_tracktor import ENTITY_MSGTRACTOR

def json_serial(obj):
  if isinstance(obj, datetime.datetime):
      serial = obj.isoformat()
      return serial

def arg_formatter():
    """
    source : https://stackoverflow.com/questions/52605094/python-argparse-increase-space-between-parameter-and-description
    """

    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)

    return formatter


def parse_args():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(),
                                     description='Email parsing and IOC enrichment')
    parser.add_argument("-i", "--input", metavar="FILENAME",
                        help="input MSG/EML file", required=True)
    args = parser.parse_args()
    return parser, args


def main():

    # TODO
    # clean parsed 'received from' field with regex (see 'eml/test3/received_fields.json')
    # check domains for whitelists
    # check for base_tag
    # anonymizacia hlavicky
    # use redSnooper for URLS

    # NOTE : DONE
    # fixed MSG/EML header to file
    # header: remove all X-... ; use whitelist
    # extracted specific (interesting) headers
    # parse 'received from' to json

    parser, args = parse_args()
    filepath = args.input

    if not os.path.isfile(filepath):
        parser.error(f"\n[!] The file '{filepath}' does not exist")
    else:
        logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                            filename='logs/gulmighami.log', level=logging.DEBUG)
        logger = logging.getLogger('SINGHAM')

        sample_name, sample_extension = os.path.splitext(filepath)
        if sample_extension not in ['.eml', '.EML', '.msg', '.MSG']:
            print('ERROR: File to process must be EML/MSG')
            logging.error('File to process must be EML/MSG')
            sys.exit(0)

        if sample_extension.lower() == ".msg":
            entity_msgtractor = ENTITY_MSGTRACTOR()
            entity_msgtractor.process_sample(filepath)
        elif sample_extension.lower() == ".eml":
            entity_emltractor = ENTITY_EMLTRACTOR()
            entity_emltractor.process_sample(filepath)


if __name__ == "__main__":
    main()

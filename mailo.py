import os
import argparse
import logging
import sys

from extractors.eml_extractor import EMLExtractor
from extractors.msg_extractor import MSGExtractor


def banner():
    print(r"""
             _
            [_|
       .-=====|=-.
       | m@ilo   |
       |_________|__/
           ||
           ||   
     """)

def arg_formatter():
    """
    source : https://stackoverflow.com/questions/52605094/python-argparse-increase-space-between-parameter-and-description
    """

    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)

    return formatter

# print extracted data, received_parsed, email_body
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(),
                                     description='Parse EML or MSG email file types and extract various Indicators of Compromise.')
    parser.add_argument(
        '-q', '--quiet', help="do not print the banner", action='store_true')
    parser.add_argument("-i", "--input", metavar="FILENAME",
                        help="input file (MSG/EML file types supported)", required=True)
    # parser.add_argument("-a", "--anonymize", action='store_true',
    #                     help="anonymize email headers (NOTE: experimental feature)")
    
    args = parser.parse_args()
    return parser, args


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/mailo.log", level=logging.DEBUG)
    logger = logging.getLogger('__name__')


def main():

    # TODO
    # anonymize header
    # convert time fields to one format
    # clean parsed 'received from' field with regex (see 'eml/test3/received_fields.json')
    # check domains for whitelists
    # check for base_tag

    # NOTE : DONE
    # fixed incorect MAC regex
    # fixed MSG/EML header to file
    # header: remove all X-... ; use whitelist
    # extracted specific (interesting) headers
    # parse 'received from' to json

    init_logger()

    parser, args = parse_args()

    if not args.quiet:
        banner()

    filepath = args.input

    if not os.path.isfile(filepath):
        logging.error(f"Provided file '{filepath}' does not exist")
        parser.error(f"\n[ERROR] Provided file '{filepath}' does not exist")
    else:
        sample_name, sample_extension = os.path.splitext(filepath)
        if sample_extension not in ['.eml', '.EML', '.msg', '.MSG']:
            print('[ERROR] File to process must be EML/MSG file type')
            logging.error('File to process must be EML/MSG file type')
            print("\nExiting program ...\n")
            sys.exit(1)

        if sample_extension.lower() == ".msg":
            entity_msgtractor = MSGExtractor()
            entity_msgtractor.process_sample(filepath)
        elif sample_extension.lower() == ".eml":
            entity_emltractor = EMLExtractor()
            entity_emltractor.process_sample(filepath)


if __name__ == "__main__":
    main()

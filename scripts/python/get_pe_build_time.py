from pefile import PE
from argparse import ArgumentParser
from datetime import datetime

def main():
    argp = ArgumentParser()
    argp.add_argument('file', type=str)
    args = argp.parse_args()

    build_time = datetime.utcfromtimestamp(PE(args.file).FILE_HEADER.TimeDateStamp)
    print(str(build_time), end='')

if __name__ == '__main__':
    main()
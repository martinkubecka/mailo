<p align="center">
<img src="https://github.com/martinkubecka/mailo/blob/main/docs/banner.png" alt="Logo">
<p align="center"><b>Process EML and MSG file types and extract various Indicators of Compromise.</b><br>
</p>

---
<h2 id="table-of-contents">Table of Contents</h2>

- [:memo: Pre-requisites](#memo-pre-requisites)
  - [:package: Installing Required Packages](#package-installing-required-packages)
- [:desktop\_computer: Usage](#desktop_computer-usage)
- [:toolbox: Development](#toolbox-development)
  - [:office: Virtual environment](#office-virtual-environment)

---
## :memo: Pre-requisites

- clone this project with the following command

```
$ git clone https://github.com/martinkubecka/mailo.git
```

### :package: Installing Required Packages

```
$ pip install -r requirements.txt
```

- `mail-parser` package requires `Email::Outlook::Message` Perl module for reading Outlook MSG files without need to install Outlook itself
- you can install this Perl module with `libemail-outlook-message-perl` package on Debian based systems with the following command

```
$ sudo apt-get install libemail-outlook-message-perl
```

- for other systems see `INSTALLATION` section in the [email-outlook-message-perl](https://github.com/mvz/email-outlook-message-perl) repository

---
## :desktop_computer: Usage

```
usage: mailo.py [-h] [-q] (-i FILENAME | -b PATH)

Process EML and MSG file types and extract various Indicators of Compromise.

options:
  -h, --help                     show this help message and exit
  -q, --quiet                    do not print banner
  -i FILENAME, --input FILENAME  input file (MSG/EML file types supported)
  -b PATH, --bulk-input PATH     input folder (MSG/EML file types supported)
```

---
## :toolbox: Development

### :office: Virtual environment

1. use your package manager to install `python-pip` if it is not present on your system
3. install `virtualenv`
4. verify installation by checking the `virtualenv` version
5. inside the project directory create a virtual environment called `venv`
6. activate it by using the `source` command
7. you can deactivate the virtual environment from the parent folder of `venv` directory with the `deactivate` command

```
$ sudo apt-get install python-pip
$ pip install virtualenv
$ virtualenv --version
$ virtualenv --python=python3 venv
$ source venv/bin/activate
$ deactivate
```

---

<div align="right">
<a href="#table-of-contents">[ Table of Contents ]</a>
</div>
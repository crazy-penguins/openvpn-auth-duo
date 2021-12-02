SHELL := /bin/bash
setup:
	if which python3.9 && [ ! -d bin ] ; then python3.9 -m venv . ; fi
	source bin/activate \
	  && python -m pip install -q -U pip setuptools wheel twine \
	  && pip install -e .

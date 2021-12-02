SHELL := /bin/bash
setup:
	if which python3.9 && [ ! -d bin ] ; then python3.9 -m venv . ; fi
	source bin/activate \
	  && python -m pip install -q -U pip setuptools wheel twine \
	  && pip install -e .
clean:
	rm -rf build openvpn-auth-duo.egg-info
	rm -rf dist
build:
	source bin/activate \
	  && python setup.py sdist
upload:
	source bin/activate \
	  && twine upload dist/*
deploy: clean build upload


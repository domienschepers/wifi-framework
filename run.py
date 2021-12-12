#!/usr/bin/env python3
import argparse
import atexit

# Import dependencies and libraries.
from dependencies.libwifi.wifi import *
from library.station import Authenticator, Supplicant
from library.testcase import Test
from library.daemon import Daemon

# Metadata.
NAME = "Wi-Fi Framework"
VERSION = "1.0"

# Examples:
# ./run.py wlan1 example-demo

# ----------------------------------- Helper Functions --------------------------------

def dynamically_load_test(name):
	"""Avoids us from editing this file when writing new tests."""
	# Search each file matching our test-template.
	for test in glob("test-*.py"):
		module = __import__(test[:-3])
		# Load all our test classes.
		for attribute_name in dir(module):
			attribute = getattr(module, attribute_name)
			# Check for classes with a name attribute.
			if isinstance(attribute, type) and hasattr(attribute,"name"):
				if attribute.name == name:
					return attribute
	# Requested test could not be found.
	return None
	
def cleanup():
	station.stop()

# ----------------------------------- Main Function -----------------------------------

if __name__ == "__main__":

	# Arguments.
	parser = argparse.ArgumentParser(description=f"{NAME} (Version {VERSION}).")
	parser.add_argument('iface', help="Interface.")
	parser.add_argument('name', help="Name of test to run.")
	parser.add_argument('--config', type=str, default=None, help="Configuration file.")
	parser.add_argument('--binary', type=str, default=None, help="Custom hostapd/wpa_supplicant binary.")
	parser.add_argument('--debug', type=int, default=0, help="Debug output level.")
	options = parser.parse_args()
	
	# Set debug verbosity of the logger.
	change_log_level(-options.debug)
	
	# Load the requested test.
	test_class = dynamically_load_test(options.name)
	if test_class == None:
		log(STATUS, f"Test name '{options.name}' not found.")
		quit(1)
	del options.name

	# Detect the type of test and instantiate it
	if issubclass(test_class, Daemon):
		# Create a Daemon instance and execute that
		station = test_class(options)
	else:
		# Load the station to execute the test case
		options.test = test_class()
		if options.test.kind == Test.Authenticator:
			station = Authenticator(options)
		elif options.test.kind == Test.Supplicant:
			station = Supplicant(options)
		
	# Run the requested test kind.
	atexit.register(cleanup)
	station.run()
	

from setuptools import setup

setup(
	name='token_cli',
	version='0.0.1',
	description='this program is the cli for the Token Network',
	author='C3ald',
	py_modules=['token_cli'],
	install_requires=['click', 'tabulate', 'requests'],
	entry_points={'console_scripts': ['token_cli = token_cli:cli'],},
)
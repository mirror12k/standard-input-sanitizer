from distutils.core import setup
setup(
  name = 'standard_input_sanitizer',
  packages = ['standard_input_sanitizer'],
  version = '0.1',
  license='MIT',
  description = 'Recursive input sanitizer',
  author = 'mirror12k',
  url = 'https://github.com/mirror12k/standard-input-sanitizer',
  download_url = 'https://github.com/mirror12k/standard-input-sanitizer/releases/latest/download/release.zip',
  keywords = ['sanitizer', 'xss', 'sqli', 'log4j'],
  install_requires=[],
  classifiers=[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: MIT License',
    'Programming Language :: Python :: 3.8',
  ],
)
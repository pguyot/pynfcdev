from setuptools import setup

setup(
    name='pynfcdev',
    version='0.2.0',
    description='Python package to use /dev/nfc* interface provided by ST25R391x driver',
    url='https://github.com/pguyot/pynfcdev',
    author='Paul Guyot',
    author_email='pguyot@kallisys.net',
    license='GPLv2+',
    packages=['nfcdev'],
    install_requires=['ioctl_opt',
                      ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
        'Operating System :: POSIX :: Linux',        
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
    ],
)

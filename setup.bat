

set INCLUDE=C:\temp\mbedtls\include
set LIBPATH=C:\temp\mbedtls\visualc\VS2010\x64\Release\

rem py -3.7 -m setup.py install

py -3.7 -m setup.py bdist_wheel sdist
pause
:loop
(
REM if code is not on your C drive switch to the correct drive letter
REM g:
REM use the full pathname to where your code is located
cd slingbox
slingbox_server.exe
REM or if your using python use the full path to whatever python interpreter you're using.
REM "c:\Program Files\Python39\python.exe" slingbox_server.py 
)
goto :loop

 
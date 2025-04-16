Para ver CommanLine que tengan el parámetro -Dhttps.proxyPassword (podemos obtener contraseñas en texto claro)

```
-Dhttps.proxyPassword
| table([ComputerName, CommandLine, LocalIP])
```
import jinja2
import os
h={}
try: 
    h['sql_db'] = os.environ['DBNAME']
    h['sql_host'] = os.environ['SQLHOST']
    h['sql_pw'] = os.environ['SQLPWD']
    h['sql_user'] = os.environ['SQLUSER']
    h['sql_port'] = os.environ['SQLPORT']
    h['sql_engine'] = os.environ['DBENGINE']
    h['dojo_media'] = os.environ['DOJOMEDIALOC']
    h['dojo_static'] = os.environ['DOJOSTATICLOC']
    h['dojo_secret'] = os.environ['DOJOSECRET']
    h['dojo_dir'] = os.environ['DOJODIR']

except KeyError:
    print("it looks like you're missing one or more env vars!") 
    print(os.environ)
    os._exit(3)
t=jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="./")).get_template('settings.docker.template')
f = open('settings.py','w') 
f.write(t.render(s=h))
f.close

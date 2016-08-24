#!/bin/bash
echo "=============================================================================="
echo "DefectDojo Docker Setup"
echo "Installing required packages"
echo "=============================================================================="
echo
echo "=============================================================================="
echo "Installing wkhtmltopdf"
echo "=============================================================================="
echo
#Install wkhtmltopdf
cd /tmp && wget http://download.gna.org/wkhtmltopdf/0.12/0.12.3/wkhtmltox-0.12.3_linux-generic-amd64.tar.xz
tar xvfJ /tmp/wkhtmltox-0.12.3_linux-generic-amd64.tar.xz
cp /tmp/wkhtmltox/bin/wkhtmltopdf /usr/local/bin/wkhtmltopdf
rm /tmp/*.xz

echo "=============================================================================="
echo "Installing Bower"
echo "=============================================================================="
echo
cd /django-DefectDojo
# bower install
npm install -g bower

# Detect Python version
PYV=`python -c "import sys;t='{v[0]}.{v[1]}'.format(v=list(sys.version_info[:2]));sys.stdout.write(t)";`
if [[ "$PYV"<"2.7" ]]; then
    echo "ERROR: DefectDojo requires Python 2.7+"
    exit 1;
else
    echo "Leaving Django 1.8.4 requirement"
fi

echo "=============================================================================="
echo "Pip install required components"
echo "=============================================================================="
echo
pip install .

#echo "=============================================================================="
#echo "Copying settings.py"
#echo "=============================================================================="
#echo
#Copying setting.py temporarily so that collect static will run correctly
#Can't create the settings file yet as values are created from .env file via docker-compose
#cp /django-DefectDojo/dojo/settings.dist.py /django-DefectDojo/dojo/settings.py
#sed -i  "s#DOJO_STATIC_ROOT#$PWD/static/#g" /django-DefectDojo/dojo/settings.py

echo "=============================================================================="
echo "Installing bower"
echo "=============================================================================="
echo
cd /django-DefectDojo/components
bower install --allow-root
#cd /django-DefectDojo/
#python manage.py collectstatic --noinput

#echo "=============================================================================="
#echo "Removing temporary files"
#echo "=============================================================================="
#echo
#Copying setting.py temporarily so that collect static will run correctly
#rm /django-DefectDojo/dojo/settings.py

echo "=============================================================================="
echo
echo "SUCCESS! Startup Docker Dojo: docker-compose up"
echo
echo "=============================================================================="

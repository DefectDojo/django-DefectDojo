# code: language=Dockerfile

# The code for the build image should be idendical with the code in
# Dockerfile.django to use the caching mechanism of Docker.

FROM python:2 as build
WORKDIR /app
RUN \
  apt-get -y update && \
  apt-get -y install \
    dnsutils \
    mysql-client \
    postgresql-client \
    xmlsec1 \
    && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists && \
  true
COPY requirements.txt ./
RUN pip wheel --wheel-dir=/tmp/wheels -r ./requirements.txt

FROM build AS collectstatic

USER root
RUN \
  apt-get -y update && \
  apt-get -y install apt-transport-https ca-certificates && \
  curl -sSL https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - && \
  echo "deb https://deb.nodesource.com/node_11.x stretch main" | tee /etc/apt/sources.list.d/nodesource.list && \
  curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - && \
  echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list && \
  apt-get -y update && \
  apt-get -y install nodejs && \
  apt-get -y install --no-install-recommends yarn && \
  apt-get clean && \
  rm -rf /var/lib/apt/lists && \
  true

RUN pip install \
	--no-cache-dir \
	--no-index \
  --find-links=/tmp/wheels \
	-r ./requirements.txt

COPY components/ ./components/
COPY manage.py ./
COPY dojo/ ./dojo/
RUN \
  cp dojo/settings/settings.dist.py dojo/settings/settings.py
RUN \
  cd components && \
  yarn && \
  cd .. && \
  python manage.py collectstatic && \
  true

FROM nginx
COPY --from=collectstatic /app/static/ /usr/share/nginx/html/static/
COPY wsgi_params nginx/nginx.conf /etc/nginx/
COPY docker/entrypoint-nginx.sh /
RUN \
  chmod -R g=u /var/cache/nginx && \
  chmod -R g=u /var/run && \
  true
ENV \
  DD_UWSGI_PASS="uwsgi_server" \
  DD_UWSGI_HOST="uwsgi" \
  DD_UWSGI_PORT="3031"
USER 1001
ENTRYPOINT ["/entrypoint-nginx.sh"]

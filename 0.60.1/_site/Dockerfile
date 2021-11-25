FROM jekyll/jekyll:pages

ENV BUNDLE_PATH=$GEM_HOME

COPY Gemfile* /srv/jekyll/

WORKDIR /srv/jekyll

RUN chown jekyll:jekyll -R /usr/gem

RUN apk update && \
    apk add ruby-dev gcc make curl build-base libc-dev libffi-dev zlib-dev \
    libxml2-dev libgcrypt-dev libxslt-dev python

RUN bundle config build.nokogiri --use-system-libraries && bundle install

EXPOSE 4000
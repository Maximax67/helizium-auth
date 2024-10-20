FROM node:22-alpine AS app

RUN apk update && apk upgrade

RUN mkdir -p /usr/src/app/node_modules
RUN chown -R node:node /usr/src/app

WORKDIR /usr/src/app

USER node

COPY --chown=node:node package*.json ./
RUN npm install

EXPOSE 3500

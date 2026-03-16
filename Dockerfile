FROM node:22-alpine AS app

RUN apk update && apk upgrade

RUN mkdir -p /usr/src/app/node_modules
RUN chown -R node:node /usr/src/app

WORKDIR /usr/src/app

USER node

COPY --chown=node:node package*.json ./
RUN npm install

COPY --chown=node:node . .

ARG APP_PORT=3500
ENV APP_PORT=${APP_PORT}

EXPOSE ${APP_PORT}

CMD ["npm", "run", "start:dev"]

FROM denoland/deno:latest

WORKDIR /app
COPY server.ts .

RUN deno cache server.ts

EXPOSE 8000

CMD ["run", "--allow-net", "--allow-env", "server.ts"]

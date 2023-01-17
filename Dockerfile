FROM handsonsecurity/seed-ubuntu:dev AS builder

COPY .  /app
WORKDIR /app

RUN apt-get install -y libpcap0.8-dev
RUN make clean
RUN make build


FROM handsonsecurity/seed-ubuntu:large as attacker

COPY --from=builder /app/dist /app
WORKDIR /app

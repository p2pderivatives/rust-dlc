FROM postgres:16.2

RUN mkdir certs
COPY ./testconfig/oracle/certs/db/db.crt /certs/
COPY ./testconfig/oracle/certs/db/db.key /certs/
RUN chmod 600 /certs/db.key
RUN chown postgres /certs/db.key

CMD ["postgres"]

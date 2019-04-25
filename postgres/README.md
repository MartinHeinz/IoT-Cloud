## Database Docker image

This is directory that contains necessary files for building and running standalone PostgreSQL database container.

### Building and Running

* Create external network that this container will connect to (network belongs to `iot_cloud` service):
    * Check if it's already created: `docker network ls | grep iot-cloud_shared_net`
      If there is output such as: <code>e7add65e3e97&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;iot-cloud_shared_net&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;bridge&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;local</code>
      Then you can skip to next step.
    * Create network: `docker network create -d bridge --subnet=172.26.0.0/16 iot-cloud_shared_net`
* Build and Run: `docker-compose up`. 

### Miscellaneous
* Upon first run (when container is created) container creates all databases using `create_db.sh`
* To backup data from any database you can run: <br/>
`docker exec -it $(docker-compose ps -q ) pg_dump -U<user> --column-inserts --data-only <db_name> > backup.sql` <br/>
example:
`docker exec -it $(docker-compose ps -q ) pg_dump -Upostgres --column-inserts --data-only postgres > backup.sql` <br/>
This saves all insert statements necessary to recreate current state of database into file `backup.sql`
* `docker exec -it $(docker-compose ps -q ) psql -Upostgres -c '\z'`  to show all tables in the database.
* `docker exec -it $(docker-compose ps -q ) psql -Upostgres -c 'create table user()'` to write queries directly
* `docker exec -i $(docker-compose ps -q ) psql -Upostgres < backup.sql`  to restore backed up data
* Preferably access using _pgadmin4_ should be used with username _postgres_ at `0.0.0.0` and with exposed port from _docker-compose.override_ (by default: `5430`)

## Benchmarks

This is directory that contains scripts and reports from system benchmarks

### Running specific benchmarks
* To run _Blind Index_ and _OPE_ benchmark use: `pytest . --benchmark-histogram`
* To run MQTT benchmark use `query.sh` with updated `BROKER`, `USERNAME`, `PASSWORD`, `TOPIC` arguments and id of your `network`
* To run _OpenDoor_ scanner:
    * Install it using instructions at <https://github.com/stanislav-web/OpenDoor>
    * Run using: `python opendoor.py --host https://127.0.0.1 --reports html`
* To run see hash function distribution plot run `tuple_generation.py` and optionally switch between hash functions by switching the `x` assignments in the file
 (`# x = [...]`)
* TODO locust

### Reports
* All reports are inside `./reports` folder grouped by specific benchmark
* To correctly display interactive plots for _Blind Index_ and _OPE_ please use web browser, e.g. _Chrome_
* For _Hawkeye scanner_ there are two reports - one for server application and one for client (user and device CLI) <br>
    These files contain all found vulnerabilities with their level, description and file + line location
* For MQTT broker benchmark, there are also 2 reports - one with authentication caching and one without, there is also a `query.sh`
 file with command that was used to run those benchmarks
* For _OpenDoor_ scan there is one file showing all files the scanner looked for and whether they were found or not
* TODO tuple_generation
* TODO locust

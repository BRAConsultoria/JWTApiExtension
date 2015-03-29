start:
	@docker-compose up -d

clean:
	@docker-compose stop
	@docker-compose rm --force

restart: clean start

test:
	@docker run -i -t -v `pwd`:/var/www/mockserver -w /var/www/mockserver --link behatjwtextension_proxy_1:mockserver.test leanlabs/php-behat php5 vendor/bin/behat --format pretty

.PHONY: start test clean restart

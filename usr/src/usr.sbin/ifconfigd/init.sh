groupadd -g 666 _ifconfigd

useradd -d /var/empty \
		-s /sbin/nologin \
		-G _ifconfigd \
		-c "Ifconfig Daemon"  \
		-u 666 _ifconfigd

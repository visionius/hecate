#
# heKate (Linux version) / Demo Make file
#

TARGET	= hecate
CC	= gcc
CFLAGS	= -Wall -O2 -o

all:	hecate

hecate:
	${CC} ${CFLAGS} ${TARGET} hecate.c distorm3.a

clean:
	/bin/rm -rf *.o ${TARGET} 

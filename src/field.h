#ifndef FIELD_H
#define FIELD_H

typedef struct {
	char name[128];
	char format[4];
	int offset;
} field_type;

#endif // vim:filetype=c

#ifndef SENSORD_H
#define SENSORD_H
struct sensor_reading { int value; int status; };
int sensord_init(int max);
int sensord_get_reading(const char *name, struct sensor_reading *out);
void sensord_shutdown(void);
#endif

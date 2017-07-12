// Copyright 2016 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0
// <http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.


#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/bpf.h>

#define HEADERS_SIZE 54
#define NEEDLE_LEN 5

#define SEC(NAME) __attribute__((section(NAME), used))
SEC(".classifier")
int process_packet(struct __sk_buff *skb)
{
    // Having needle as const or #define as string, moves it to another section
    // in elf and this code won't have access to that.
    char needle[] = { 'H', 'E', 'L', 'L', 'O' };
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    int data_len = data_end - data + 1;

    int i = 0;
    int j = 0;
    for (i = HEADERS_SIZE; i < data_len; i++) {
        if (((char *) data)[i] == needle[j]) {
            if (j == NEEDLE_LEN - 1) {
                return i - (NEEDLE_LEN - 1) - HEADERS_SIZE;
            } else {
                j++;
            }
        } else {
            j = 0;
        }
    }

    return -1;
}

/*
 * Copyright (C) 2021  University of Alberta
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

/*
 * general.c
 *
 *  Created on: May 14, 2021
 *      Author: Robert Taylor
 */
#include <FreeRTOS.h>
#include <os_task.h>
#include "HL_reg_system.h"

#include <csp/csp.h>
#include <csp/csp_endian.h>
#include <main/system.h>
#include "general.h"
#include "services.h"
#include "util/service_utilities.h"
#include "privileged_functions.h"
#include "task_manager/task_manager.h"

#define XSTR_(X) STR_(X)
#define STR_(X) #X

SAT_returnState general_app(csp_packet_t *packet);
void general_service(void * param);

//for testing only. do hex dump
//size is the number of bytes we want to print
void hex_dump_(char *stuff, int size) {
  uint32_t current_packet_index = 0;
  printf("printing number of bytes: %u\n", size);
    int j = 0;
    for (j = 0; j < size; j += 1) {
      if (stuff[current_packet_index] < 0x10) {
        printf("0");
      }
      printf("%X ", stuff[current_packet_index]);
      current_packet_index += 1;
      if (current_packet_index % 16 == 0) {
        printf("\n");
      }
    }
    printf("\n");
}

csp_conn_t *conn;

/**
 * @brief
 *      Start the general server task
 * @details
 *      Starts the FreeRTOS task responsible for accepting incoming
 *      general packets
 * @param None
 * @return SAT_returnState
 *      success report
 */
SAT_returnState start_general_service(void) {
    if (xTaskCreate((TaskFunction_t)general_service,
                    "general_service", 300, NULL, NORMAL_SERVICE_PRIO,
                    NULL) != pdPASS) {
        ex2_log("FAILED TO CREATE TASK general_service\n");
        return SATR_ERROR;
    }
    return SATR_OK;
}

/**
 * @brief
 *      FreeRTOS general server task
 * @details
 *      Accepts incoming csp connections to perform tasks not covered by other services
 * @param void* param
 * @return None
 */
void general_service(void * param) {
    csp_socket_t *sock;
    sock = csp_socket(CSP_SO_RDPREQ); // require RDP connection
    csp_bind(sock, TC_GENERAL_SERVICE);
    csp_listen(sock, SERVICE_BACKLOG_LEN);

    for(;;) {
        csp_packet_t *packet;
        if ((conn = csp_accept(sock, CSP_MAX_TIMEOUT)) == NULL) {
            /* timeout */
            continue;
        }
        while ((packet = csp_read(conn, 50)) != NULL) {
            if (general_app(packet) != SATR_OK) {
                // something went wrong, this shouldn't happen
                csp_buffer_free(packet);
            } else {
                if (!csp_send(conn, packet, 50)) {
                    csp_buffer_free(packet);
                }
            }
        }
        csp_close(conn);
    }
}

/**
 * @brief
 *      Handle incoming csp_packet_t
 * @details
 *      Takes a csp packet destined for the general service handler,
 *              and will handle the packet based on it's subservice type.
 * @param csp_packet_t *packet
 *              Incoming CSP packet - we can be sure that this packet is
 *              valid and destined for this service.
 * @return SAT_returnState
 *      success report
 */
SAT_returnState general_app(csp_packet_t *packet) {
    uint8_t ser_subtype = (uint8_t)packet->data[SUBSERVICE_BYTE];
    int8_t status;
    char reboot_type;
    uint32_t tsk = 0;
    uint32_t delay = 0;

    user_info *tsk_lst = NULL;
    uint32_t size;

    switch (ser_subtype) {
    case REBOOT:

        reboot_type = packet->data[IN_DATA_BYTE];

        switch(reboot_type) {
        case 'A':
        case 'B':
        case 'G':
            status = 0;
            break;
        default:
            status = -1;
            break;
        }
        memcpy(&packet->data[STATUS_BYTE], &status, sizeof(int8_t));
        set_packet_length(packet, sizeof(int8_t) + 1);  // +1 for subservice
        csp_send(conn, packet, 50);

        if (status == 0) {
            reboot_system(reboot_type);
        }
        break;

    case SET_TASK_DELAY:
        memcpy(&tsk, &packet->data[IN_DATA_BYTE], sizeof(uint32_t));
        memcpy(&delay, &packet->data[IN_DATA_BYTE + 4], sizeof(uint32_t));
        if (ex2_set_task_delay((TaskHandle_t)tsk, delay)) {
            status = 0;
            set_packet_length(packet, sizeof(int8_t) + 1);  // +1 for subservice
            break;
        }
        set_packet_length(packet, sizeof(int8_t) + 1);  // +1 for subservice
        status = -1;
        break;

    case GET_TASK_DELAY:
        memcpy(&tsk, &packet->data[IN_DATA_BYTE], sizeof(uint32_t));
        delay = ex2_get_task_delay((TaskHandle_t)tsk);
        memcpy(&packet->data[OUT_DATA_BYTE], &delay, sizeof(int32_t));
        set_packet_length(packet, sizeof(int32_t) + sizeof(int8_t)*2);
        status = 0;
        break;

    case GET_TASK_LIST:
        // TODO: make this bounded and use Dustin's string send code from logging
        ex2_get_task_list(&tsk_lst, &size);
        uint32_t written = 0;
        int i;
        char * loc = packet->data + OUT_DATA_BYTE;
        for (i = 0; i < size; i++) {
            written += sprintf(loc, "%010d %." XSTR_(configMAX_TASK_NAME_LEN) "s\r\n", tsk_lst->task, tsk_lst->task_name);
            loc = packet->data + (OUT_DATA_BYTE + written);
        }
        hex_dump_(packet->data, 100);
        set_packet_length(packet, written + 2 + 1);  // +1 for subservice, +1 for status
        status = 0;
        break;

    case GET_TASK_WATERMARK:
        memcpy(&tsk, &packet->data[IN_DATA_BYTE], sizeof(uint32_t));
        UBaseType_t watermark = dev_ex2_get_task_high_watermark(tsk);
        memcpy(&packet->data[OUT_DATA_BYTE], &watermark, sizeof(UBaseType_t));
        set_packet_length(packet, sizeof(UBaseType_t) + 2); // +1 for subservice, +1 for status
        status = 0;
        break;

    default:
        ex2_log("No such subservice\n");
        return SATR_PKT_ILLEGAL_SUBSERVICE;
    }
    memcpy(&packet->data[STATUS_BYTE], &status, sizeof(int8_t));  // 0 for success
    return SATR_OK;
}

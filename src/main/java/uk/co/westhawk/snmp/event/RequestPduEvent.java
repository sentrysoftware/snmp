// NAME
//      $RCSfile: RequestPduEvent.java,v $
// DESCRIPTION
//      [given below in javadoc format]
// DELTA
//      $Revision: 1.5 $
// CREATED
//      $Date: 2006/02/09 14:30:18 $
// COPYRIGHT
//      Westhawk Ltd
// TO DO
//

/*
 * Copyright (C) 2005 - 2006 by Westhawk Ltd
 * <a href="www.westhawk.co.uk">www.westhawk.co.uk</a>
 *
 * Permission to use, copy, modify, and distribute this software
 * for any purpose and without fee is hereby granted, provided
 * that the above copyright notices appear in all copies and that
 * both the copyright notice and this permission notice appear in
 * supporting documentation.
 * This software is provided "as is" without express or implied
 * warranty.
 * author <a href="mailto:snmp@westhawk.co.uk">Tim Panton</a>
 */
package uk.co.westhawk.snmp.event;

/*-
 * ╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲
 * SNMP Java Client
 * ჻჻჻჻჻჻
 * Copyright 2023 Sentry Software, Westhawk
 * ჻჻჻჻჻჻
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 *
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * ╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱╲╱
 */

import uk.co.westhawk.snmp.stack.*;


/**
 * The RequestPduEvent class. This class is delivered when a pdu is received.
 *
 * <p>
 * RequestPduEvents are fired in case of a GetRequest, SetRequest,
 * GetNextRequest, GetBulkRequest (SNMPv2c, SNMPv3), Inform 
 * (SNMPv2c, SNMPv3) PDU that could be decoded and matched by one 
 * of the SnmpContext classes.
 * </p>
 *
 * @since 4_14
 * @author <a href="mailto:snmp@westhawk.co.uk">Birgit Arkesteijn</a>
 * @version $Revision: 1.5 $ $Date: 2006/02/09 14:30:18 $
 */
public class RequestPduEvent extends DecodedPduEvent
{
    private static final String     version_id =
        "@(#)$Id: RequestPduEvent.java,v 1.5 2006/02/09 14:30:18 birgit Exp $ Copyright Westhawk Ltd";

/** 
 * The constructor for a decoded request pdu event. The SnmpContext
 * classes will fire decoded request pdu events.
 *
 * @param source The source (SnmpContext) of the event
 * @param pdu The pdu
 * @param port The remote port number of the host where the pdu came from
 *
 */
public RequestPduEvent(Object source, Pdu pdu, int port) 
{
    super(source, pdu, port);
}


}

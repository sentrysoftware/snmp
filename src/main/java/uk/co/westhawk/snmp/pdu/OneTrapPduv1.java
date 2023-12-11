// NAME
//      $RCSfile: OneTrapPduv1.java,v $
// DESCRIPTION
//      [given below in javadoc format]
// DELTA
//      $Revision: 3.7 $
// CREATED
//      $Date: 2006/03/23 14:54:09 $
// COPYRIGHT
//      Westhawk Ltd
// TO DO
//

/*
 * Copyright (C) 2001 - 2006 by Westhawk Ltd
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


package uk.co.westhawk.snmp.pdu;

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
import java.util.*;
import java.io.*;

import uk.co.westhawk.snmp.stack.*;
import uk.co.westhawk.snmp.util.*;

/**
 * This class represents the ASN SNMPv1 Trap PDU object. 
 * See <a href="http://www.ietf.org/rfc/rfc1157.txt">RFC1157-SNMP</a>.
 *
 * @deprecated  As of 4_14, just use {@link TrapPduv1} 
 * @author <a href="mailto:snmp@westhawk.co.uk">Birgit Arkesteijn</a>
 * @version $Revision: 3.7 $ $Date: 2006/03/23 14:54:09 $
 */
public class OneTrapPduv1 extends TrapPduv1 
{
    private static final String     version_id =
        "@(#)$Id: OneTrapPduv1.java,v 3.7 2006/03/23 14:54:09 birgit Exp $ Copyright Westhawk Ltd";


/** 
 * Constructor.
 *
 * @param con The context v1 of the OneTrapPduv1
 * @see SnmpContext
 */
public OneTrapPduv1(SnmpContext con) 
{
    super(con);
}

/** 
 * Constructor.
 *
 * @param con The context v1 of the OneTrapPduv1
 * @see SnmpContext
 */
public OneTrapPduv1(SnmpContextPool con) 
{
    super(con);
}

}

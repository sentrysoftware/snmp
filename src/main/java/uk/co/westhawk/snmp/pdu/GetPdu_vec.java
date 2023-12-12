// NAME
//      $RCSfile: GetPdu_vec.java,v $
// DESCRIPTION
//      [given below in javadoc format]
// DELTA
//      $Revision: 3.13 $
// CREATED
//      $Date: 2006/11/29 16:12:50 $
// COPYRIGHT
//      Westhawk Ltd
// TO DO
//

/*
 * Copyright (C) 1995, 1996 by West Consulting BV
 *
 * Permission to use, copy, modify, and distribute this software
 * for any purpose and without fee is hereby granted, provided
 * that the above copyright notices appear in all copies and that
 * both the copyright notice and this permission notice appear in
 * supporting documentation.
 * This software is provided "as is" without express or implied
 * warranty.
 * author <a href="mailto:snmp@westhawk.co.uk">Tim Panton</a>
 * original version by hargrave@dellgate.us.dell.com (Jordan Hargrave)
 */


/*
 * Copyright (C) 1996 - 2006 by Westhawk Ltd
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
import uk.co.westhawk.snmp.stack.*;
import java.lang.*;

/**
 * <p>
 * The GetPdu_vec class will ask for a number of objects (OIDs), based 
 * on the Get request.
 * </p>
 *
 * <p>
 * Specify with <em>addOid()</em> the OIDs that should be requested with this
 * PDU request. No more than <em>count</em> (see constructor) should be added.
 * Add an Observer to the PDU with <em>addObserver()</em>, and send the PDU
 * with <em>send()</em>.
 * </p>
 *
 * <p>
 * If no exception occurred whilst receiving the response, the Object to the 
 * update() method of the Observer will be an array of
 * varbinds, so they may contains any AsnObject type.
 * If an exception occurred, that exception will be passed as the Object
 * to the update() method.
 * </p>
 *
 * @author <a href="mailto:snmp@westhawk.co.uk">Birgit Arkesteijn</a>
 * @version $Revision: 3.13 $ $Date: 2006/11/29 16:12:50 $
 * @see Pdu#addOid
 * @see Pdu#send
 * @see varbind
 * @see OneIntPdu
 */
public class GetPdu_vec extends GetPdu 
{
    private static final String     version_id =
        "@(#)$Id: GetPdu_vec.java,v 3.13 2006/11/29 16:12:50 birgit Exp $ Copyright Westhawk Ltd";

    varbind[]  value;

    /**
     * Constructor.
     *
     * @param con The context of the request
     * @param count The number of OIDs to be get
     */
    public GetPdu_vec(SnmpContextBasisFace con, int count) 
    {
        super(con);
        value = new varbind[count];
    }

    /**
     * The value of the request is set. This will be called by
     * Pdu.fillin().
     *
     * @param n the index of the value
     * @param var the value
     * @see Pdu#new_value 
     */
    protected void new_value(int n, varbind var) 
    {
        if (n <value.length) 
        {
            value[n] = var;
        }
    }

    /**
     * This method notifies all observers. 
     * This will be called by Pdu.fillin().
     * 
     * <p>
     * If no exception occurred whilst receiving the response, the Object to the 
     * update() method of the Observer will be an array of
     * varbinds, so they may contains any AsnObject type.
     * If an exception occurred, that exception will be passed as the Object
     * to the update() method.
     * </p>
     */
    protected void tell_them()  
    {
        notifyObservers(value);
    }
}

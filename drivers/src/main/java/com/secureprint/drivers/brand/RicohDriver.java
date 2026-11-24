package com.secureprint.drivers.brand;

/**
 * Ricoh Aficio / IM series over PCL5 on raw 9100.
 *
 * <p>Ricoh's native language is RPCS, but every Aficio/IM model accepts PCL5 and, more usefully
 * for us, PJL. Where a device only speaks RPCS, it is registered with a vendor-API driver in a
 * downstream plugin jar instead — the registry does not care which driver id maps to which class.
 */
public final class RicohDriver extends PclRawSocketDriver {

    public RicohDriver() {
        super(600);
    }

    @Override
    public String driverId() {
        return "ricoh.aficio.pcl5.raw9100";
    }

    @Override
    public String description() {
        return "Ricoh Aficio / IM (PCL5 raster over raw TCP 9100)";
    }
}

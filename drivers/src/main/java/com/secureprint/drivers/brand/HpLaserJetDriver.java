package com.secureprint.drivers.brand;

/**
 * HP LaserJet / Color LaserJet over PCL5 on raw 9100.
 *
 * <p>HP's PJL is the reference implementation and uses {@code CODE=} status codes plus a
 * {@code DISPLAY=} string. Colour models also accept PCL5c, so colour jobs can stay on this
 * driver; monochrome models silently drop colour, so the release planner refuses colour jobs
 * for devices that did not advertise COLOR capability at discovery time.
 */
public final class HpLaserJetDriver extends PclRawSocketDriver {

    public HpLaserJetDriver() {
        super(600);
    }

    @Override
    public String driverId() {
        return "hp.laserjet.pcl5.raw9100";
    }

    @Override
    public String description() {
        return "HP LaserJet / Color LaserJet (PCL5 raster over raw TCP 9100)";
    }

    @Override
    protected String pdlName() {
        return "PCL5c";
    }
}

package com.secureprint.drivers.registry;

import com.secureprint.drivers.spi.PrinterDriver;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Lookup from {@code driverId} (and model strings) to a {@link PrinterDriver}.
 *
 * <p>Two registration paths, on purpose:
 * <ul>
 *   <li><b>Built-in</b> — shipped in this jar, registered in {@link #withBuiltins()}.</li>
 *   <li><b>ServiceLoader</b> — brand plugins dropped into the classpath by an integrator without
 *       forking this project. This is how you add a proprietary vendor that needs an SDK.</li>
 * </ul>
 *
 * <p>Model-string matching exists because discovery often reports "HP Color LaserJet MFP M479fdw"
 * and not a driver id; the registry maps known model prefixes to the best driver, and unmapped
 * models fall back to a protocol-family driver (IPP if reachable, else PCL5). That fallback is
 * what makes a dozen-plus heterogeneous brands tractable: you only write a custom driver for a
 * model that misbehaves under the generic path.
 */
public final class DriverRegistry {

    private final Map<String, PrinterDriver> byId = new ConcurrentHashMap<>();
    private final List<ModelRule> modelRules = new java.util.concurrent.CopyOnWriteArrayList<>();

    public record ModelRule(String modelPrefix, String driverId, int priority) {
    }

    public static DriverRegistry withBuiltins() {
        DriverRegistry registry = new DriverRegistry();
        registry.register(new com.secureprint.drivers.brand.HpLaserJetDriver());
        registry.register(new com.secureprint.drivers.brand.KyoceraDriver());
        registry.register(new com.secureprint.drivers.brand.RicohDriver());
        registry.register(new com.secureprint.drivers.brand.PostScriptDriver(
                "canon.imagerunner.postscript.raw9100",
                "Canon imageRUNNER (PostScript over raw TCP 9100)", 600,
                java.util.Set.of("MONO", "COLOR", "DUPLEX", "A4", "A3", "STAPLE")));
        registry.register(new com.secureprint.drivers.brand.PostScriptDriver(
                "konica.bizhub.postscript.raw9100",
                "Konica Minolta bizhub (PostScript over raw TCP 9100)", 600,
                java.util.Set.of("MONO", "COLOR", "DUPLEX", "A4", "A3", "STAPLE")));
        registry.register(new com.secureprint.drivers.brand.IppDriver(
                "generic.ipp",
                "Generic IPP/AirPrint (any brand)", java.util.Set.of(
                "MONO", "COLOR", "DUPLEX", "A4", "A3", "LETTER", "LEGAL")));

        // Model-prefix hints. Longest/most-specific match wins via priority.
        registry.addModelRule(new ModelRule("hp color laserjet", "hp.laserjet.pcl5.raw9100", 10));
        registry.addModelRule(new ModelRule("hp laserjet", "hp.laserjet.pcl5.raw9100", 10));
        registry.addModelRule(new ModelRule("kyocera", "kyocera.ecosys.pcl5.raw9100", 10));
        registry.addModelRule(new ModelRule("taskalfa", "kyocera.ecosys.pcl5.raw9100", 10));
        registry.addModelRule(new ModelRule("ricoh", "ricoh.aficio.pcl5.raw9100", 10));
        registry.addModelRule(new ModelRule("aficio", "ricoh.aficio.pcl5.raw9100", 10));
        registry.addModelRule(new ModelRule("canon imagerunner", "canon.imagerunner.postscript.raw9100", 10));
        registry.addModelRule(new ModelRule("bizhub", "konica.bizhub.postscript.raw9100", 10));
        registry.addModelRule(new ModelRule("konica", "konica.bizhub.postscript.raw9100", 10));
        return registry;
    }

    public static DriverRegistry withBuiltinsAndPlugins(ClassLoader loader) {
        DriverRegistry registry = withBuiltins();
        ServiceLoader.load(PrinterDriver.class, loader).forEach(registry::register);
        return registry;
    }

    public void register(PrinterDriver driver) {
        PrinterDriver previous = byId.putIfAbsent(driver.driverId(), driver);
        if (previous != null) {
            throw new IllegalStateException("driver id already registered: " + driver.driverId());
        }
    }

    public void replace(PrinterDriver driver) {
        byId.put(driver.driverId(), driver);
    }

    public void addModelRule(ModelRule rule) {
        modelRules.add(rule);
    }

    public Optional<PrinterDriver> byId(String driverId) {
        return Optional.ofNullable(byId.get(driverId));
    }

    /** Resolves a discovered model string to the best driver, or empty if none matches. */
    public Optional<PrinterDriver> forModel(String model) {
        if (model == null || model.isBlank()) {
            return Optional.empty();
        }
        String lower = model.toLowerCase(Locale.ROOT);
        return modelRules.stream()
                .filter(r -> lower.contains(r.modelPrefix()))
                .sorted(Comparator.comparingInt(ModelRule::priority).reversed()
                        .thenComparing(r -> r.modelPrefix().length(), Comparator.reverseOrder()))
                .map(r -> byId.get(r.driverId()))
                .filter(java.util.Objects::nonNull)
                .findFirst();
    }

    public List<String> registeredDriverIds() {
        return byId.keySet().stream().sorted().toList();
    }

    public int size() {
        return byId.size();
    }
}

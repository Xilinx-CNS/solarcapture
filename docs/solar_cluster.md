Solar Cluster (solar_clusterd) is now included with SolarCapture.  
Later versions of Onload intend to not include this component.  

This component is built by default, artefacts will be in build_products/usr/bin/solar_clusterd and build_products/usr/lib/python3/dist-packages/solar_clusterd
as well as within the tarball, if you choose to build that.  ('make tarball').  
If you have a version that is provided by Onload, you may use that instead.  It is identical to this version.

The Solar Cluster functionality is to enable setting up a new interface, which is a filtered version of an existing interface. 
This may be used to shard incoming traffic across multiple instances of an application when a single instance cannot keep up with the full feed.

See the User Guide for more details on usage.

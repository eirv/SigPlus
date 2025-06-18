-optimizationpasses 5
-mergeinterfacesaggressively
-overloadaggressively
-repackageclasses sig

-keepclassmembers class sig.SigPlus {
  t(...);
  n(...);
}


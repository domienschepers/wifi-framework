# Dependencies

The framework uses `hostap` and `libwifi` as dependencies.

For more information on its setup, see the [installation and configuration instructions](../setup/README.md).

## Hostap

We provide ```hostap``` (Version 2.9) which includes the modifications and extensions for our framework.

If you want to inspect all the applied modifications, then you can execute:
```
git clone -b 'hostap_2_9' --single-branch --depth 1 git://w1.fi/srv/git/hostap.git hostap_2_9_original
diff -r hostap_2_9/ hostap_2_9_original/ -x '*.d' -x '*.o' -x '*.service'
```

Note that the file `wpaspy.py` in the `dependencies` directory is a symbolic link to the `wpaspy.py` module of `hostap`.
This is done to make it easier to import the `wpaspy` module in python.

## Libwifi

[Libwifi](https://github.com/vanhoefm/libwifi) is an experimental library offering an implementation for common Wi-Fi functionality.

The library is used often in our framework, and can be pulled using the following commands:
```
git submodule init
git submodule update
```


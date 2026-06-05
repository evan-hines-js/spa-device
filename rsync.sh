#!/bin/bash
rsync -az --delete --exclude='target' ./ ubuntu@10.0.0.59:~/spa-device/

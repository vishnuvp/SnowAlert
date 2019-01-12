#!/usr/bin/Rscript

require('dplyr')
results <- read.csv(file("stdin"),stringsAsFactors=FALSE)
grouped <- result %>% group_by(CITY) %>% summarize(num_logins=length(EVENT_TIME), num_unique_users=length(unique(USER_ID)), num_successful_logins=length(which(LOGIN_STATUS=='Success')), num_days=length(unique(DAY)))
grouped$average_per_day = grouped$num_successful_logins/grouped$num_days
write.csv(grouped)

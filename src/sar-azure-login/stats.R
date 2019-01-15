#!/usr/bin/Rscript

require('dplyr')
results <- read.csv(file("stdin"),stringsAsFactors=FALSE)
num_days_total <- length(unique(results$DAY))
grouped <- results %>% group_by(CITY, STATE) %>% summarize(num_logins=length(EVENT_TIME), num_unique_users=length(unique(USER_ID)), num_successful_logins=length(which(LOGIN_STATUS=='Success')), num_days=length(unique(DAY)), percent_of_days=num_days/num_days_total)
grouped$average_per_day_when_active = grouped$num_successful_logins/grouped$num_days
grouped$average_per_day_overall = grouped$num_successful_logins/num_days_total
write.csv(grouped)
